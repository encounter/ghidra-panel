package re.mkw.srejaas;

import com.google.protobuf.Empty;
import ghidra.framework.Application;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.server.RepositoryManager;
import ghidra.server.UserManager;
import ghidra.server.remote.GhidraServer;
import ghidra.util.exception.DuplicateNameException;
import io.grpc.stub.StreamObserver;
import re.mkw.srejaas.proto.*;
import re.mkw.srejaas.reflect.GhidraServerSupport;
import re.mkw.srejaas.reflect.LocalFileSystemSupport;
import re.mkw.srejaas.reflect.RepositoryManagerSupport;
import re.mkw.srejaas.reflect.RepositorySupport;

import javax.security.auth.login.FailedLoginException;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class GrpcImpl extends GhidraGrpc.GhidraImplBase {
  private final RepositoryManager repositoryManager;
  private final UserManager userManager;

  public GrpcImpl() {
    GhidraServer ghidraServer = GhidraServerSupport.getGhidraServer();
    repositoryManager = GhidraServerSupport.getRepositoryManager(ghidraServer);
    userManager = repositoryManager.getUserManager();
  }

  @Override
  public void getVersion(Empty request, StreamObserver<Version> responseObserver) {
    responseObserver.onNext(buildVersion());
    responseObserver.onCompleted();
  }

  @Override
  public void getRepositoriesAndUsers(Empty request, StreamObserver<GetRepositoriesAndUsersReply> responseObserver) {
    String repositoriesDir = RepositoryManagerSupport.getRootDir(repositoryManager).getAbsolutePath();
    GetRepositoriesAndUsersReply.Builder builder = GetRepositoriesAndUsersReply.newBuilder()
        .setVersion(buildVersion())
        .setRepositoriesDir(repositoriesDir);
    for (String name : RepositoryManagerSupport.getRepositoryNames(repositoryManager)) {
      ghidra.server.Repository repository = RepositoryManagerSupport.getRepository(repositoryManager, name);
      builder.addRepositories(buildRepository(repository));
    }
    for (String user : userManager.getUsers()) {
      builder.addUsers(buildUser(user));
    }
    responseObserver.onNext(builder.build());
    responseObserver.onCompleted();
  }

  @Override
  public void getRepositories(Empty request, StreamObserver<GetRepositoriesReply> responseObserver) {
    String repositoriesDir = RepositoryManagerSupport.getRootDir(repositoryManager).getAbsolutePath();
    GetRepositoriesReply.Builder builder = GetRepositoriesReply.newBuilder().setRepositoriesDir(repositoriesDir);
    for (String name : RepositoryManagerSupport.getRepositoryNames(repositoryManager)) {
      ghidra.server.Repository repository = RepositoryManagerSupport.getRepository(repositoryManager, name);
      builder.addRepositories(buildRepository(repository));
    }
    responseObserver.onNext(builder.build());
    responseObserver.onCompleted();
  }

  @Override
  public void getRepositoryUser(GetRepositoryUserRequest request, StreamObserver<GetRepositoryUserReply> responseObserver) {
    ghidra.server.Repository repository = RepositoryManagerSupport.getRepository(repositoryManager, request.getRepository());
    if (repository == null) {
      responseObserver.onError(io.grpc.Status.NOT_FOUND.withDescription("Repository not found").asRuntimeException());
      return;
    }
    ghidra.framework.remote.User user = repository.getUser(request.getUsername());
    GetRepositoryUserReply.Builder builder = GetRepositoryUserReply.newBuilder();
    if (user != null) {
      builder.setResult(buildUserWithPermission(user));
    }
    responseObserver.onNext(builder.build());
    responseObserver.onCompleted();
  }

  @Override
  public void getUsers(Empty request, StreamObserver<GetUsersReply> responseObserver) {
    GetUsersReply.Builder builder = GetUsersReply.newBuilder();
    for (String user : userManager.getUsers()) {
      builder.addUsers(buildUser(user));
    }
    responseObserver.onNext(builder.build());
    responseObserver.onCompleted();
  }

  @Override
  public void addUser(AddUserRequest request, StreamObserver<Empty> responseObserver) {
    try {
      userManager.addUser(request.getUsername());
      responseObserver.onNext(Empty.getDefaultInstance());
      responseObserver.onCompleted();
    } catch (DuplicateNameException e) {
      responseObserver.onError(io.grpc.Status.ALREADY_EXISTS.withDescription(e.getMessage()).asRuntimeException());
    } catch (IOException e) {
      responseObserver.onError(io.grpc.Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void removeUser(RemoveUserRequest request, StreamObserver<Empty> responseObserver) {
    try {
      if (userManager.removeUser(request.getUsername())) {
        responseObserver.onNext(Empty.getDefaultInstance());
        responseObserver.onCompleted();
      } else {
        responseObserver.onError(io.grpc.Status.NOT_FOUND.withDescription("User not found").asRuntimeException());
      }
    } catch (IOException e) {
      responseObserver.onError(io.grpc.Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void setUserPermission(SetUserPermissionRequest request, StreamObserver<Empty> responseObserver) {
    try {
      ghidra.server.Repository repository = RepositoryManagerSupport.getRepository(repositoryManager, request.getRepository());
      if (repository == null) {
        responseObserver.onError(io.grpc.Status.NOT_FOUND.withDescription("Repository not found").asRuntimeException());
        return;
      }
      if (request.getPermission() == Permission.NONE) {
        if (RepositorySupport.removeUser(repository, request.getUsername())) {
          responseObserver.onNext(Empty.getDefaultInstance());
          responseObserver.onCompleted();
        } else {
          responseObserver.onError(io.grpc.Status.NOT_FOUND.withDescription("User not found").asRuntimeException());
        }
        return;
      }
      // Temporary hack: some users may not have been added to the UserManager
      if (!userManager.isValidUser(request.getUsername())) {
        try {
          userManager.addUser(request.getUsername());
        } catch (DuplicateNameException ignored) {
        }
      }
      if (RepositorySupport.setUserPermission(repository, request.getUsername(), request.getPermission().getNumber())) {
        responseObserver.onNext(Empty.getDefaultInstance());
        responseObserver.onCompleted();
      } else {
        responseObserver.onError(io.grpc.Status.NOT_FOUND.withDescription("User not found").asRuntimeException());
      }
    } catch (IOException e) {
      responseObserver.onError(io.grpc.Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  @Override
  public void authenticateUser(AuthenticateUserRequest request, StreamObserver<AuthenticateUserReply> responseObserver) {
    try {
      AuthenticateUserReply.Builder builder = AuthenticateUserReply.newBuilder();
      // Ensure case-insensitivity
      String username = request.getUsername();
      for (String user : userManager.getUsers()) {
        if (user.equalsIgnoreCase(request.getUsername())) {
          username = user;
          builder.setUsername(user);
          break;
        }
      }
      char[] password = request.getPassword().toCharArray();
      try {
        userManager.authenticateUser(username, password);
        builder.setSuccess(true);
      } catch (FailedLoginException e) {
        builder.setSuccess(false).setMessage(e.getMessage());
      } finally {
        Arrays.fill(password, '\0');
      }
      responseObserver.onNext(builder.build());
      responseObserver.onCompleted();
    } catch (IOException e) {
      responseObserver.onError(io.grpc.Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException());
    }
  }

  private Version buildVersion() {
    String ghidraVersion = Application.getApplicationVersion();
    String panelVersion = getClass().getPackage().getImplementationVersion();
    if (panelVersion == null) {
      panelVersion = "unknown";
    }
    return Version.newBuilder()
        .setGhidraVersion(ghidraVersion)
        .setGhidraPanelVersion(panelVersion)
        .build();
  }

  private User buildUser(String name) {
    boolean hasPassword = userManager.getPasswordExpiration(name) != 0;
    return User.newBuilder()
        .setUsername(name)
        .setHasPassword(hasPassword)
        .build();
  }

  private UserWithPermission buildUserWithPermission(ghidra.framework.remote.User user) {
    return UserWithPermission.newBuilder()
        .setUser(buildUser(user.getName()))
        .setPermission(Permission.forNumber(user.getPermissionType()))
        .build();
  }

  private Repository buildRepository(ghidra.server.Repository repository) {
    LocalFileSystem fileSystem = RepositorySupport.getFileSystem(repository);
    File root = LocalFileSystemSupport.getRoot(fileSystem);
    return Repository.newBuilder()
        .setName(repository.getName())
        .setPath(root.getAbsolutePath())
        .setAnonymousAccessAllowed(repository.anonymousAccessAllowed())
        .addAllUsers(
            Arrays.stream(RepositorySupport.getRepositoryUsers(repository))
                .map(this::buildUserWithPermission)
                .toList()
        )
        .build();
  }
}
