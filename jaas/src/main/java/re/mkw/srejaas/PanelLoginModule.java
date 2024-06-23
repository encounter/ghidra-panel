package re.mkw.srejaas;

import com.sun.security.auth.UserPrincipal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

/**
 * A JAAS {@link LoginModule} authenticates users against a Ghidra Panel installation, given a
 * username and password.
 *
 * <p>Uses Argon2id for password hashing.
 *
 * <p>For further information see <a href="https://github.com/mkw-re/ghidra-panel">Ghidra Panel
 * repo</a>.
 */
public class PanelLoginModule implements LoginModule {

  private static final String USER_PROMPT_OPTION_NAME = "USER_PROMPT";
  private static final String PASSWORD_PROMPT_OPTION_NAME = "PASSWORD_PROMPT";
  private static final String JDBC_OPTION_NAME = "JDBC";
  private static final String REPO_DIR_OPTION_NAME = "REPO_DIR";

  private Logger log;
  private Subject subject;
  private CallbackHandler callbackHandler;
  private Map<String, Object> options;
  private UserPrincipal user;
  private String username;
  private byte[] password;

  private boolean pwGhidra;
  private byte[] pwSalt;
  private byte[] pwHash;
  private boolean success;
  private boolean committed;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    this.log = LogManager.getLogger(PanelLoginModule.class);
    this.subject = subject;
    this.callbackHandler = callbackHandler;
    this.options = (Map<String, Object>) options;
  }

  @Override
  public boolean login() throws LoginException {
    getNameAndPassword();
    getPasswordHash();
    verifyPassword();
    success = true;
    user = new UserPrincipal(this.username);
    return true;
  }

  @Override
  public boolean commit() {
    if (!success) {
      return false;
    }
    if (!subject.isReadOnly()) {
      if (!user.implies(subject)) {
        subject.getPrincipals().add(user);
      }
    }
    committed = true;
    return true;
  }

  @Override
  public boolean abort() throws LoginException {
    if (!success) {
      return false;
    }
    if (!committed) {
      success = false;
      cleanup();
    } else {
      logout();
    }
    return true;
  }

  @Override
  public boolean logout() throws LoginException {
    if (subject.isReadOnly()) {
      cleanup();
      throw new LoginException("Subject is read-only");
    }
    subject.getPrincipals().remove(user);

    cleanup();
    success = false;
    committed = false;

    return false;
  }

  private void cleanup() {
    user = null;
    username = null;
    if (password != null) {
      Arrays.fill(password, (byte) 0);
      password = null;
    }
  }

  /**
   * Acquires a JDBC connection handle to the URI in options.
   *
   * @throws SQLException Failed to connect to database.
   */
  private Connection connectToDatabase() throws SQLException {
    // TODO consider caching connection handles
    String jdbc = options.getOrDefault(JDBC_OPTION_NAME, "").toString();
    if (jdbc.isEmpty()) {
      throw new SQLException("JDBC connection string not provided");
    }
    return DriverManager.getConnection(jdbc);
  }

  /**
   * Uses JAAS callback API to retrieve username and password from client.
   *
   * @throws LoginException Failed to retrieve username/password
   */
  private void getNameAndPassword() throws LoginException {
    String userPrompt = options.getOrDefault(USER_PROMPT_OPTION_NAME, "Username").toString();
    String passPrompt = options.getOrDefault(PASSWORD_PROMPT_OPTION_NAME, "Password").toString();

    List<Callback> callbacks = new ArrayList<>();
    NameCallback ncb = null;
    PasswordCallback pcb = null;

    if (username == null) {
      ncb = new NameCallback(userPrompt);
      callbacks.add(ncb);
    }
    if (password == null) {
      pcb = new PasswordCallback(passPrompt, false);
      callbacks.add(pcb);
    }

    if (!callbacks.isEmpty()) {
      try {
        callbackHandler.handle(callbacks.toArray(new Callback[0]));
        if (ncb != null) {
          username = ncb.getName();
        }
        if (pcb != null) {
          char[] tmpPassword = pcb.getPassword();
          if (tmpPassword != null) {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(tmpPassword));
            password = new byte[byteBuffer.remaining()];
            byteBuffer.get(password);
            Arrays.fill(byteBuffer.array(), (byte) 0);
            Arrays.fill(tmpPassword, '\0');
            pcb.clearPassword();
          }
        }

        if (username == null || password == null) {
          log.error("Failed to get username or password");
          throw new LoginException("Internal error");
        }
      } catch (Exception e) {
        log.error("Error during callback", e);
        throw new LoginException("Internal error");
      }
    }
    validateUsernameAndPasswordFormat();
  }

  /**
   * Validates whether user and pass provided by client don't contain invalid characters.
   *
   * @throws LoginException Invalid characters detected
   */
  private void validateUsernameAndPasswordFormat() throws LoginException {
    if (username.isEmpty() || password.length == 0) {
      throw new LoginException("Username or password is empty");
    }
    if (username.contains("\n") || username.contains("\0")) {
      throw new LoginException("Bad characters in username");
    }
    for (byte b : password) {
      if (b == '\n' || b == '\0') {
        throw new LoginException("Bad characters in password");
      }
    }
  }

  /**
   * Retrieves the password hash and salt from the database.
   *
   * @throws LoginException Database error, username doesn't exist, or user didn't set password yet.
   */
  private void getPasswordHash() throws LoginException {
    Connection dbConn = null;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {
      dbConn = connectToDatabase();

      stmt =
          dbConn.prepareStatement(
              "SELECT salt, hash FROM passwords WHERE username = ? AND format = 1");
      stmt.setString(1, this.username);

      rs = stmt.executeQuery();
      if (!rs.next()) {
        // Try to fetch unmigrated password from Ghidra's user file
        if (getPasswordHashGhidra()) {
          this.pwGhidra = true;
          return;
        }
        throw new LoginException("Authentication failed");
      }

      this.pwSalt = rs.getBytes(1);
      this.pwHash = rs.getBytes(2);
    } catch (SQLException e) {
      log.error("Failed to prepare statement", e);
      throw new LoginException("Internal error");
    } finally {
      if (stmt != null) {
        try {
          stmt.close();
        } catch (SQLException ignored) {
        }
      }
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException ignored) {
        }
      }
      if (dbConn != null) {
        try {
          dbConn.close();
        } catch (SQLException ignored) {
        }
      }
    }
  }

  /**
   * Retrieves the password hash and salt from Ghidra's user file.
   *
   * @return whether a password hash was found
   */
  private boolean getPasswordHashGhidra() {
    String repoDir = options.getOrDefault(REPO_DIR_OPTION_NAME, "").toString();
    if (repoDir.isEmpty()) {
      log.warn("REPO_DIR not provided, not falling back to Ghidra authentication");
      return false;
    }

    File userFile = new File(repoDir + "/users");
    if (!userFile.exists()) {
      log.warn("Ghidra users file doesn't exist");
      return false;
    }

    try {
      Scanner scanner = new Scanner(userFile);
      while (scanner.hasNextLine()) {
        String line = scanner.nextLine();
        if (line.startsWith(";")) {
          continue;
        }
        String[] parts = line.split(":");
        if (parts.length < 2) {
          continue;
        }
        if (parts[0].equals(this.username)) {
          byte[] hashString = parts[1].getBytes(StandardCharsets.US_ASCII);
          if (hashString.length != 4 + 32 * 2 /* base16 salt + SHA-256 hash */) {
            return false;
          }
          this.pwSalt = new byte[4];
          byte[] hashBytes = new byte[64];
          System.arraycopy(hashString, 0, this.pwSalt, 0, 4);
          System.arraycopy(hashString, 4, hashBytes, 0, 64);
          this.pwHash = Hex.decode(hashBytes);
          return true;
        }
      }
    } catch (Exception e) {
      log.error("Failed to read Ghidra users file", e);
    }
    return false;
  }

  /**
   * Hash password provided by client.
   *
   * @return Argon2id hash of password.
   */
  private byte[] hashGivenPassword() {
    Argon2Parameters params =
        new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withIterations(1)
            .withMemoryAsKB(19456)
            .withParallelism(2)
            .withSalt(this.pwSalt)
            .build();

    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(params);

    byte[] actualHash = new byte[32];
    generator.generateBytes(this.password, actualHash);
    return actualHash;
  }

  /**
   * Hash password provided by the client using salted SHA-256. (Ghidra method)
   *
   * @return SHA-256 hash of password.
   */
  private byte[] hashGivenPasswordGhidra() {
    SHA256Digest digest = new SHA256Digest();
    digest.update(this.pwSalt, 0, this.pwSalt.length);
    digest.update(this.password, 0, this.password.length);
    byte[] actualHash = new byte[digest.getDigestSize()];
    digest.doFinal(actualHash, 0);
    return actualHash;
  }

  /**
   * Verifies that given password matches hash.
   *
   * @throws LoginException Wrong password
   */
  private void verifyPassword() throws LoginException {
    byte[] actualHash;
    if (pwGhidra) {
      actualHash = hashGivenPasswordGhidra();
    } else {
      actualHash = hashGivenPassword();
    }
    /* Constant-time compare */
    boolean correct = org.bouncycastle.util.Arrays.constantTimeAreEqual(this.pwHash, actualHash);
    if (!correct) {
      throw new LoginException("Authentication failed");
    }
  }
}
