package re.mkw.srejaas.reflect;

import ghidra.server.Repository;
import ghidra.server.RepositoryManager;

import java.io.File;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;

public class RepositoryManagerSupport {
  private static MethodHandle getRootDir;
  private static MethodHandle getRepository;
  private static MethodHandle getRepositoryNames;

  public static File getRootDir(RepositoryManager mgr) {
    if (getRootDir == null) {
      try {
        Method method = RepositoryManager.class.getDeclaredMethod("getRootDir");
        method.setAccessible(true);
        getRootDir = MethodHandles.lookup().unreflect(method);
      } catch (NoSuchMethodException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (File) getRootDir.invokeExact(mgr);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }

  public static Repository getRepository(RepositoryManager mgr, String name) {
    if (getRepository == null) {
      try {
        Method method = RepositoryManager.class.getDeclaredMethod("getRepository", String.class);
        method.setAccessible(true);
        getRepository = MethodHandles.lookup().unreflect(method);
      } catch (NoSuchMethodException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (Repository) getRepository.invokeExact(mgr, name);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }

  public static String[] getRepositoryNames(RepositoryManager mgr) {
    if (getRepositoryNames == null) {
      try {
        Method method = RepositoryManager.class.getDeclaredMethod("getRepositoryNames");
        method.setAccessible(true);
        getRepositoryNames = MethodHandles.lookup().unreflect(method);
      } catch (NoSuchMethodException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (String[]) getRepositoryNames.invokeExact(mgr);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }
}
