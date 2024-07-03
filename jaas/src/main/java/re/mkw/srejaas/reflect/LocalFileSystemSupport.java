package re.mkw.srejaas.reflect;

import ghidra.framework.store.local.LocalFileSystem;

import java.io.File;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;

public class LocalFileSystemSupport {
  private static MethodHandle getRoot;

  public static File getRoot(LocalFileSystem fileSystem) {
    if (getRoot == null) {
      try {
        Field field = LocalFileSystem.class.getDeclaredField("root");
        field.setAccessible(true);
        getRoot = MethodHandles.lookup().unreflectGetter(field);
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    try {
      return (File) getRoot.invokeExact(fileSystem);
    } catch (Throwable e) {
      throw new RuntimeException(e);
    }
  }
}
