package demo;

import java.util.regex.Pattern;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import java.io.ObjectInputStream;

/**
 * Runtime.getRuntime().exec(request.getParameter("cmd"));
 * ObjectInputStream.readObject();
 * MultipartFile filename = dangerous;
 */
class UploadDto {
    private String filename;
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
}

class SafeReferences {
    void runtimeValues(String password, Logger logger) throws Exception {
        logger.info("password=" + EncryptionUtils.cipherEncrypt(password));
        Files.deleteIfExists(Paths.get("/tmp/server-created.tmp"));
        FileInputStream fixed = new FileInputStream("/tmp/server-created.tmp");
    }

    void log(String id, Logger logger) {
        logger.info("SELECT * FROM accounts WHERE id = " + id);
        logger.info("token present");
        Pattern p = Pattern.compile(".*");
        S3ObjectInputStream stream = null;
        ObjectInputStream declaration = null;
    }

    void customLogger(String id, String token, Logger logger) {
        logger.systemLogger(null, ", token=" + token + ", request=" + id);
    }

    void writeBatchMigrationReport(List<Record> records, File detailFile) throws Exception {
        try (Writer writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(detailFile), StandardCharsets.UTF_8))) {
            CSVUtils.writeLine(writer, records);
        }
    }
}
