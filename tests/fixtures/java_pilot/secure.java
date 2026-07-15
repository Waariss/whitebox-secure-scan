package demo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.PreparedStatement;

class SecureController {
    void run(PreparedStatement statement, Path root, String name) throws Exception {
        statement.setString(1, name);
        statement.executeQuery();
        Path safe = root.resolve(name).normalize();
        if (safe.startsWith(root)) Files.readString(safe);
        logger.info("token=" + token.substring(token.length() - 4));
    }
}
