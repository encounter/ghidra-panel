package re.mkw.srejaas;

import com.sun.security.auth.UserPrincipal;
import ghidra.server.UserManager;
import ghidra.server.remote.GhidraServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import re.mkw.srejaas.reflect.GhidraServerSupport;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
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
@SuppressWarnings("unused")
public class PanelLoginModule implements LoginModule {
  private static final String JDBC_OPTION_NAME = "JDBC";

  private Logger log;
  private Subject subject;
  private CallbackHandler callbackHandler;
  private Map<String, Object> options;
  private UserManager userManager;
  private UserPrincipal user;
  private String username;
  private char[] password;

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

    GhidraServer ghidraServer = GhidraServerSupport.getGhidraServer();
    this.userManager = GhidraServerSupport.getRepositoryManager(ghidraServer).getUserManager();
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
      Arrays.fill(password, '\0');
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
    List<Callback> callbacks = new ArrayList<>();
    NameCallback ncb = null;
    PasswordCallback pcb = null;

    if (username == null) {
      ncb = new NameCallback("Username");
      callbacks.add(ncb);
    }
    if (password == null) {
      pcb = new PasswordCallback("Password", false);
      callbacks.add(pcb);
    }

    if (!callbacks.isEmpty()) {
      try {
        callbackHandler.handle(callbacks.toArray(new Callback[0]));
        if (ncb != null) {
          username = ncb.getName();
        }
        if (pcb != null) {
          password = pcb.getPassword();
          pcb.clearPassword();
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
    for (char b : password) {
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
        // Fall back to Ghidra's internal user management
        if (userManager.isValidUser(this.username)) {
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
   * Verifies that given password matches hash.
   *
   * @throws LoginException Wrong password
   */
  private void verifyPassword() throws LoginException {
    if (pwGhidra) {
      try {
        userManager.authenticateUser(username, password);
      } catch (FailedLoginException e) {
        throw new LoginException("Authentication failed");
      } catch (IOException e) {
        log.error("Ghidra authentication failed", e);
        throw new LoginException("Internal error");
      }
      return;
    }

    byte[] actualHash = hashGivenPassword();
    /* Constant-time compare */
    boolean correct = org.bouncycastle.util.Arrays.constantTimeAreEqual(this.pwHash, actualHash);
    if (!correct) {
      throw new LoginException("Authentication failed");
    }
  }
}
