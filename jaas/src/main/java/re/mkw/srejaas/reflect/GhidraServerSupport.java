package re.mkw.srejaas.reflect;

import ghidra.server.RepositoryManager;
import ghidra.server.remote.GhidraServer;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;

public class GhidraServerSupport {
  private static MethodHandle getGhidraServer;
  private static MethodHandle getRepositoryManager;

  public static GhidraServer getGhidraServer() {
    if (getGhidraServer == null) {
      try {
        Field field = GhidraServer.class.getDeclaredField("server");
        field.setAccessible(true);
        getGhidraServer = MethodHandles.lookup().unreflectGetter(field);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (GhidraServer) getGhidraServer.invokeExact();
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }

  public static RepositoryManager getRepositoryManager(GhidraServer server) {
    if (getRepositoryManager == null) {
      try {
        Field field = GhidraServer.class.getDeclaredField("mgr");
        field.setAccessible(true);
        getRepositoryManager = MethodHandles.lookup().unreflectGetter(field);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (RepositoryManager) getRepositoryManager.invokeExact(server);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }
}
