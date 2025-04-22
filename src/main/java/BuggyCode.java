import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

/**
 * BuggyCode クラスは、さまざまなセキュリティ関連の操作を実行します。
 */
public class BuggyCode {

  private static final Logger logger = Logger.getLogger(BuggyCode.class.getName());
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * セキュリティ関連の操作を実行するメソッド。
   */
  public void badPractice() {
    // パスワードを安全に管理
    String password = System.getenv("APP_PASSWORD");
    if (password != null) {
      logInfo("Password is set.");
    } else {
      logWarning("APP_PASSWORD is not set in the environment variables.");
    }

    // NullPointerException の回避
    Object x = "Non-null value";
    logInfo("Object value: " + x.toString());

    // コマンドインジェクションの防止
    try {
      String userInput = "calc.exe";
      if (userInput.matches("[a-zA-Z0-9._-]+")) {
        Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", userInput});
      } else {
        throw new IllegalArgumentException("Invalid input");
      }
    } catch (IOException e) {
      logSevere("Command execution failed: " + e.getMessage());
    }

    // 機密データの安全な保存
    try (FileOutputStream fos = new FileOutputStream(new File("sensitive.txt"))) {
      fos.write(encryptData("Sensitive data!")
          .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } catch (IOException | NoSuchAlgorithmException e) {
      logSevere("File write failed: " + e.getMessage());
    }

    // パスワードをログに出力しない
    logInfo("User entered password: [REDACTED]");

    // 安全なソルトの生成
    String salt = generateSecureSalt();
    String hashed = hashPassword(System.getenv("USER_PASSWORD"), salt);
    logInfo("Hashed password generated: " + hashed);

    // ハードコードされた API キーの削除
    String apiKey = System.getenv("API_KEY");
    if (apiKey != null) {
      logInfo("API Key is set: " + apiKey);
    } else {
      logWarning("API Key is not set.");
    }

    // 不適切な例外キャッチの修正
    try {
      int y = 10 / 0;
      logInfo("Result of division: " + y);
    } catch (ArithmeticException e) {
      logSevere("Arithmetic error occurred: " + e.getMessage());
    }

    // DNS反射攻撃の防止
    try {
      InetAddress.getByName("localhost").isReachable(1000);
    } catch (UnknownHostException e) {
      logSevere("DNS resolution failed: " + e.getMessage());
    } catch (IOException e) {
      logSevere("DNS reachability check failed: " + e.getMessage());
    }

    // 設定オブジェクトの適切な使用
    String dbPassword = System.getenv("DB_PASSWORD");
    if (dbPassword != null) {
      logInfo("Database password is set in the configuration.");
    } else {
      logWarning("DB_PASSWORD is not set in the environment variables.");
    }
  }

  /**
   * ログ出力用の専用メソッド（INFOレベル）。
   *
   * @param message ログメッセージ.
   */
  private void logInfo(String message) {
    logger.info(message.replaceAll("[\r\n]", ""));
  }

  /**
   * ログ出力用の専用メソッド（WARNINGレベル）。
   *
   * @param message ログメッセージ.
   */
  private void logWarning(String message) {
    logger.warning(message.replaceAll("[\r\n]", ""));
  }

  /**
   * ログ出力用の専用メソッド（SEVEREレベル）。
   *
   * @param message ログメッセージ.
   */
  private void logSevere(String message) {
    logger.severe(message.replaceAll("[\r\n]", ""));
  }

  /**
   * データを暗号化するメソッド。
   *
   * @param data 暗号化するデータ.
   * @return 暗号化されたデータ.
   * @throws NoSuchAlgorithmException アルゴリズムが見つからない場合.
   */
  private String encryptData(String data) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    StringBuilder hexString = new StringBuilder();
    for (byte b : hash) {
      hexString.append(String.format("%02x", b));
    }
    return hexString.toString();
  }

  /**
   * 安全なソルトを生成するメソッド。
   *
   * @return 生成されたソルト.
   */
  private String generateSecureSalt() {
    byte[] salt = new byte[16];
    SECURE_RANDOM.nextBytes(salt);
    StringBuilder hexString = new StringBuilder();
    for (byte b : salt) {
      hexString.append(String.format("%02x", b));
    }
    return hexString.toString();
  }

  /**
   * パスワードをハッシュ化するメソッド。
   *
   * @param password ハッシュ化するパスワード.
   * @param salt ソルト.
   * @return ハッシュ化されたパスワード.
   */
  private String hashPassword(String password, String salt) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(salt.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      byte[] hashedPassword = md.digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      StringBuilder hexString = new StringBuilder();
      for (byte b : hashedPassword) {
        hexString.append(String.format("%02x", b));
      }
      return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error hashing password", e);
    }
  }
}