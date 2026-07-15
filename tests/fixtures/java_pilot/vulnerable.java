package demo;

import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.multipart.MultipartFile;
import com.amazonaws.auth.BasicAWSCredentials;

class VulnerableController {
    void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement statement, MultipartFile file) throws Exception {
        String token = request.getHeader("Authorization");
        logger.info("request token=" + token);
        BasicAWSCredentials creds = new BasicAWSCredentials("AKIA1234567890ABCDEF", "synthetic-secret-key");
        Runtime.getRuntime().exec(request.getParameter("cmd"));
        statement.executeQuery("SELECT * FROM accounts WHERE id = " + request.getParameter("id"));
        file.transferTo(Paths.get(file.getOriginalFilename()).toFile());
        Files.readString(Paths.get(request.getParameter("path")));
        new ObjectInputStream(request.getInputStream()).readObject();
    }
}
