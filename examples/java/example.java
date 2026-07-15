class Example {
  void review(String token, String path, java.sql.PreparedStatement statement) throws Exception {
    logger.info("token=" + token);
    java.nio.file.Files.readString(java.nio.file.Paths.get(path));
    java.nio.file.Files.readString(java.nio.file.Paths.get("/tmp/example.txt"));
    statement.setString(1, path);
  }
}
