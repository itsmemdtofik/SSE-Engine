MIT License

Copyright (c) [year] [fullname]

/** 
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


import javax.swing.*;
import com.google.gson.reflect.TypeToken;
import org.json.simple.parser.ParseException;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.tika.exception.TikaException;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.sax.BodyContentHandler;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.xml.sax.SAXException;
import java.io.BufferedReader;
import java.io.Console;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.*;
import java.util.*;
import java.util.List;
import javax.crypto.*;

public class App {
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, ParseException {

        runSSEEngineDemo();
    }

    public static void runSSEEngineDemo() throws NoSuchAlgorithmException, IOException, ParseException {
        try {

            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");

            Color folderColor = new Color(50, 100, 200);
            Color fileColor = new Color(100, 200, 50);
            Color backgroundColor = new Color(230, 230, 230);

            UIManager.put("FileChooser.directoryFont", new Font(Font.SANS_SERIF, Font.BOLD, 14));
            UIManager.put("FileChooser.fileFont", new Font(Font.SANS_SERIF, Font.PLAIN, 14));
            UIManager.put("FileChooser.listFont", new Font(Font.SANS_SERIF, Font.PLAIN, 14));

            UIManager.put("FileChooser.upFolderIcon", UIManager.get("FileChooser.newFolderIcon"));
            UIManager.put("FileChooser.homeFolderIcon", UIManager.get("FileChooser.newFolderIcon"));
            UIManager.put("FileChooser.openFolderIcon", new FolderIcon(folderColor));
            UIManager.put("FileChooser.fileNameText", fileColor);

            UIManager.put("Panel.background", backgroundColor);
            UIManager.put("OptionPane.background", backgroundColor);

            UIManager.put("FileChooser.listViewBorder", BorderFactory.createLineBorder(backgroundColor, 5));
        } catch (Exception e) {
            System.out.println("Failed to set the look and feel.");
        }

        int choice;

        while (true) {
            System.out.println("\n----------------------------------------------------\n");
            System.out.println("1 - Add More Files");
            System.out.println("2 - Start Indexing");
            System.out.println("3 - Searching");
            System.out.println("4 - Exit");
            System.out.println("\n----------------------------------------------------\n");
            System.out.print("Enter Your Choice : ");

            try {
                choice = scanner.nextInt();
            } catch (InputMismatchException e) {
                System.out.println("Invalid input. Please enter a valid choice.");
                scanner.nextLine(); /* Clear the invalid input from the scanner */
                continue;
            }

            System.out.println("\n----------------------------------------------------\n");

            switch (choice) {
                case 1 -> openFileSelectionDialog();
                case 2 -> {
                    try {
                        IndexingAndSearching.indexing();
                    } catch (TikaException | SAXException e) {
                        e.printStackTrace();
                    }
                }
                case 3 -> IndexingAndSearching.searching();
                case 4 -> {
                    System.out.println("Exiting...\n\n");
                    IndexingAndSearching.saveIndexToFile();
                    return;
                }
                default -> System.out.println("Invalid Choice!\n\n");
            }
        }
    }

    /**
     * !Open the UI of Adding Files From System
     * 
     * @param openFileSelectionDialog()
     */
    public static void openFileSelectionDialog() {
        String destinationDirectoryPath = "Data";

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Files or Directory To Add");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        fileChooser.setMultiSelectionEnabled(true);
        fileChooser.setPreferredSize(new Dimension(800, 600));

        int result = fileChooser.showOpenDialog(null);

        if (result == JFileChooser.APPROVE_OPTION) {
            File[] selectedFilesOrDirectories = fileChooser.getSelectedFiles();

            File destinationDirectory = new File(destinationDirectoryPath);
            if (!destinationDirectory.exists() || !destinationDirectory.isDirectory()) {
                System.out.println("Invalid destination directory: " + destinationDirectoryPath);
                return;
            }

            for (File selectedFileOrDirectory : selectedFilesOrDirectories) {
                try {
                    if (selectedFileOrDirectory.isDirectory()) {
                        copyDirectory(selectedFileOrDirectory.toPath(), destinationDirectory.toPath());
                        System.out
                                .println("Directory copied successfully: " + selectedFileOrDirectory.getAbsolutePath());
                    } else {
                        copyFile(selectedFileOrDirectory.toPath(), destinationDirectory.toPath());
                        System.out.println("File copied successfully: " + selectedFileOrDirectory.getAbsolutePath());
                    }
                } catch (IOException e) {
                    System.out.println("Failed to copy: " + selectedFileOrDirectory.getAbsolutePath());
                }
            }
        } else {
            System.out.println("No file or directory selected.");
        }
    }

    /**
     * !Copy File
     * 
     * @param source
     * @param destination
     * @throws IOException
     */
    public static void copyFile(Path source, Path destination) throws IOException {
        Files.copy(source, destination.resolve(source.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * !Copy the Directory
     * 
     * @param source
     * @param destination
     * @throws IOException
     */
    public static void copyDirectory(Path source, Path destination) throws IOException {
        Path destinationDirectory = destination.resolve(source.getFileName());
        Files.walkFileTree(source, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                Path targetPath = destinationDirectory.resolve(source.relativize(dir));
                Files.createDirectories(targetPath);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (!file.getFileName().toString().equals("desktop.ini")) {
                    Files.copy(file, destinationDirectory.resolve(source.relativize(file)),
                            StandardCopyOption.REPLACE_EXISTING);
                }
                return FileVisitResult.CONTINUE;

            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                System.out.println("Failed to copy: " + file);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * !UI Icons
     */
    static class FolderIcon implements Icon {
        private final Color color;

        public FolderIcon(Color color) {
            this.color = color;
        }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            g.setColor(color);
            g.fillRect(x + 2, y + 2, getIconWidth() - 4, getIconHeight() - 4);

            // Draw rounded border
            g.setColor(Color.BLACK);
            g.drawRoundRect(x, y, getIconWidth() - 1, getIconHeight() - 1, 5, 5);
        }

        @Override
        public int getIconWidth() {
            return 16;
        }

        @Override
        public int getIconHeight() {
            return 16;
        }
    }
}

/**
 * !Indexing And Searching Class
 * 
 * @throws NoSuchAlgorithmException
 * @throws IOException
 * @throws TikaException
 * @throws SAXException
 */
class IndexingAndSearching {

    private static Map<String, Map<String, Integer>> index = new HashMap<>();
    private static Map<String, String> fileIdMap = new HashMap<>();
    private static SecretKey mek;

    private static final String folderPath = "Data";
    private static final String indexPath = "Output\\index.json";
    private static final String fileIdMapPath = "Output\\fileIDmap.json";

    private static final String keyFilePath = "Key\\key.txt";
    private static final int batchSize = 100;
    private static int fileCounter = 0;

    private static Set<String> existingEncryptedFileNames;

    private static final byte[] saltForEncryption = { 0x03f };
    private static final String PASSWORD_FILE = "Password\\password.txt";

    private static Scanner scanner = new Scanner(System.in);

    public static void saveIndexToFile() {
        JSONWriter.writeToJsonFile(index, indexPath);
        JSONWriter.writeToJsonFile(fileIdMap, fileIdMapPath);
    }

    /**
     * !Indexing
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws TikaException
     * @throws SAXException
     */
    public static void indexing() throws NoSuchAlgorithmException, IOException, TikaException, SAXException {
        loadExistingIndex();
        String storedHash = Cryptography.readStoredHash();
        String password = Cryptography.getPassword(storedHash);
        String hashedPassword = Cryptography.hashPassword(password);
        AtomicInteger tokenCount = new AtomicInteger(0);

        if (storedHash == null) {
            // If the password file doesn't exist, prompt the user for a password and store
            // the hashed password
            Cryptography.storeHashedPassword(hashedPassword);
            System.out.println("\n----------------------------------------------------\n");
            System.out.println("Password Created successfully!");
            System.out.println("\n----------------------------------------------------\n");
        } else {
            if (hashedPassword.equals(storedHash)) {
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("User logged in successfully.");
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("Valid user. Continuing...");
            } else {
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("Invalid user. Exiting...");
                System.out.println("\n----------------------------------------------------\n");
                System.exit(0);
            }
        }

        SecretKey secretKey = Cryptography.generateSecretKeyFromPassword(password);
        File keyFile = new File(keyFilePath);

        if (keyFile.exists()) {
            // Key file exists, decrypt the MEK from the file
            String encryptedMEK = Cryptography.readEncryptedMEK();
            mek = Cryptography.decryptMEK(encryptedMEK, secretKey);
        } else {
            // Key file doesn't exist, generate a new MEK
            mek = Cryptography.generateMEK();
            String encryptedMEK = Cryptography.encryptMEK(mek, secretKey);
            Cryptography.writeEncryptedMEK(encryptedMEK);
        }
        Map<String, String> newFileIdMap = new HashMap<>(fileIdMap);
        Map<String, Map<String, Integer>> newIndex = new HashMap<>();

        HashSet<String> stopWords = new HashSet<>(
                Arrays.asList("a", "an", "the", "and", "or", "not", "is", "are", "was", "were", ""));

        File folder = new File(folderPath);
        if (folder.listFiles() == null || folder.listFiles().length == 0) {
            System.out.println("Error: Folder is empty or does not exist.");
            return;
        }

        Parser parser = new AutoDetectParser();
        ParseContext parseContext = new ParseContext();
        parseContext.set(Parser.class, parser);

        existingEncryptedFileNames = new HashSet<>(fileIdMap.values());

        boolean allFilesIndexed = true;
        for (File file : folder.listFiles()) {
            String encryptedFileName = Cryptography.encryptFileName(file.getName(), mek);

            if (!existingEncryptedFileNames.contains(encryptedFileName)) {
                allFilesIndexed = false;
                break;
            }
        }

        if (allFilesIndexed) {
            System.out.println("Reindexing not needed. All files are already indexed.");
            return;
        }

        double startIndexing = System.currentTimeMillis() / 1000.0;
        List<File> batchFiles = new ArrayList<>();

        for (File file : folder.listFiles()) {
            String encryptedFileName = Cryptography.encryptFileName(file.getName(), mek);
            boolean isIndexed = existingEncryptedFileNames.contains(encryptedFileName);

            if (isIndexed) {
                continue; // Skip already indexed files
            }

            String fileId = Cryptography.generateFileId(file.getName());
            fileIdMap.put(fileId, encryptedFileName);
            fileCounter++;
            batchFiles.add(file);

            if (batchFiles.size() >= batchSize) {

                processBatchFiles(batchFiles, stopWords, parser, parseContext, mek, index, newFileIdMap, tokenCount);
                batchFiles.clear();
            }
        }

        if (!batchFiles.isEmpty()) {
            processBatchFiles(batchFiles, stopWords, parser, parseContext, mek, index, newFileIdMap, tokenCount);
        }

        double endIndexing = System.currentTimeMillis() / 1000.0;

        mergeIndexWithExistingIndex(newIndex);
        fileIdMap = newFileIdMap;

        System.out.println("\n----------------------------------------------------\n");
        double totalTimeOfIndexing = endIndexing - startIndexing;
        System.out.println("The total time taken to generate the tokens: "
                + String.format("%.3f", totalTimeOfIndexing) + " seconds");
        System.out.println("The total number of Unique Tokens: " + tokenCount);
        System.out.println("\n----------------------------------------------------\n");
        System.out.println("The total files indexed: " + fileCounter);
        System.out.println("\n----------------------------------------------------\n");

    }

    /**
     * !Processing the file(Multithreading)
     * 
     * @param files
     * @param stopWords
     * @param parser
     * @param parseContext
     * @param mek
     * @param index
     * @param newFileIdMap
     * @param tokenCount
     * @throws IOException
     * @throws TikaException
     * @throws SAXException
     */
    private static void processBatchFiles(List<File> files,
            HashSet<String> stopWords, Parser parser, ParseContext parseContext,
            SecretKey mek, Map<String, Map<String, Integer>> index,
            Map<String, String> newFileIdMap, AtomicInteger tokenCount)
            throws IOException, TikaException, SAXException {

        int availableProcessors = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(availableProcessors);
        List<Callable<Void>> tasks = new ArrayList<>();
        Set<String> uniqueTokens = new HashSet<>(); // Track unique tokens

        for (File file : files) {
            Callable<Void> task = () -> {
                String fileName = file.getName();
                String currentFileId = Cryptography.generateFileId(fileName);
                String encryptedFileName = Cryptography.encryptFileName(fileName, mek);
                newFileIdMap.put(currentFileId, encryptedFileName);

                BodyContentHandler handler = new BodyContentHandler(-1);
                Metadata metadata = new Metadata();
                parser.parse(file.toURI().toURL().openStream(), handler, metadata, parseContext);
                String[] tokens = handler.toString().toLowerCase().replaceAll("[^a-z\\s-.()/,;=]", " ")
                        .split("[\\s-.()/,;=]+");

                Map<String, Integer> tokenFrequency = new HashMap<>();

                for (String token : tokens) {
                    if (stopWords.contains(token)) {
                        continue;
                    }

                    String hashedToken = Cryptography.hashString(token, mek);

                    if (uniqueTokens.add(hashedToken)) {
                        tokenCount.incrementAndGet(); // Increment unique token count
                    }

                    tokenFrequency.put(hashedToken, tokenFrequency.getOrDefault(hashedToken, 0) + 1);
                }

                synchronized (index) {
                    updateIndex(index, currentFileId, tokenFrequency);
                }

                return null;
            };

            tasks.add(task);
        }

        try {
            executor.invokeAll(tasks);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    /**
     * !Updating Index
     * 
     * @param index
     * @param currentFileId
     * @param tokenFrequency
     */
    private static void updateIndex(Map<String, Map<String, Integer>> index,
            String currentFileId,
            Map<String, Integer> tokenFrequency) {
        for (Map.Entry<String, Integer> entry : tokenFrequency.entrySet()) {
            String token = entry.getKey();
            int count = entry.getValue();

            if (index.containsKey(token)) {
                Map<String, Integer> existingTokenData = index.get(token);
                existingTokenData.put(currentFileId, count);
            } else {
                Map<String, Integer> newTokenFrequency = new HashMap<>();
                newTokenFrequency.put(currentFileId, count);
                index.put(token, newTokenFrequency);
            }
        }
    }

    /**
     * !Merging Index with Existing Index
     * 
     * @param newIndex
     */
    public static void mergeIndexWithExistingIndex(Map<String, Map<String, Integer>> newIndex) {
        for (Map.Entry<String, Map<String, Integer>> entry : newIndex.entrySet()) {

            String keyword = entry.getKey();
            Map<String, Integer> tokenData = entry.getValue();

            if (index.containsKey(keyword)) {
                Map<String, Integer> existingTokenData = index.get(keyword);

                for (Map.Entry<String, Integer> tokenEntry : tokenData.entrySet()) {
                    String fileId = tokenEntry.getKey();
                    int frequency = tokenEntry.getValue();

                    existingTokenData.merge(fileId, frequency, Integer::sum);
                }
            } else {
                index.put(keyword, tokenData);
            }
        }
    }

    /**
     * ! Load existing index
     */
    public static void loadExistingIndex() {

        try {
            Path indexPathFile = Path.of(indexPath);
            if (!Files.exists(indexPathFile)) {
                // Index file does not exist, initialize empty index and fileIdMap
                index = new HashMap<>();
                fileIdMap = new HashMap<>();
                return;
            }

            // Read the index file
            String jsonString = Files.readString(indexPathFile);
            JSONParser parser = new JSONParser();
            JSONObject jsonIndex = (JSONObject) parser.parse(jsonString);

            // Populate the index map
            index = new HashMap<>();
            for (Object key : jsonIndex.keySet()) {
                String keyword = (String) key;
                JSONObject tokenMap = (JSONObject) jsonIndex.get(key);
                Map<String, Integer> tokenData = new HashMap<>();
                for (Object fileId : tokenMap.keySet()) {
                    String fileIdStr = (String) fileId;
                    int frequency = ((Long) tokenMap.get(fileId)).intValue();
                    tokenData.put(fileIdStr, frequency);
                }
                index.put(keyword, tokenData);
            }

            // Read the fileIdMap file
            Path fileIdMapPathFile = Path.of(fileIdMapPath);
            if (Files.exists(fileIdMapPathFile)) {
                jsonString = Files.readString(fileIdMapPathFile);
                JSONObject jsonFileIdMap = (JSONObject) parser.parse(jsonString);

                // Populate the fileIdMap
                fileIdMap = new HashMap<>();
                for (Object key : jsonFileIdMap.keySet()) {
                    String fileId = (String) key;
                    String encryptedFileName = (String) jsonFileIdMap.get(key);
                    fileIdMap.put(fileId, encryptedFileName);
                }
            } else {
                fileIdMap = new HashMap<>();
            }
        } catch (IOException | ParseException e) {
            e.printStackTrace();
            // Handle the exception as needed
        }
    }

    /**
     * !Searching
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static void searching() throws NoSuchAlgorithmException, IOException {
        if (index.isEmpty() || fileIdMap.isEmpty()) {
            loadIndexFromFile();
            loadFileIdMapFromFile();
            // Load existing index from JSON file// Load existing file ID map from JSON file
        }

        if (index == null || fileIdMap == null) {
            System.out.println("\n----------------------------------------------------\n");
            System.out.println("No index and file ID map found. Please perform indexing first.");
            System.out.println("\n----------------------------------------------------\n");
            return;
        }
        String storedHash = Cryptography.readStoredHash();

        String password = Cryptography.getPassword(storedHash);
        String hashedPassword = Cryptography.hashPassword(password);
        if (storedHash == null) {
            /*
             * If the password file doesn't exist, prompt user for password and store hashed
             * password
             */
            Cryptography.storeHashedPassword(hashedPassword);
            System.out.println("\n----------------------------------------------------\n");
            System.out.println("Password Created successfully!");
            System.out.println("\n----------------------------------------------------\n");
        } else {
            // If the password file exists, prompt user for password and compare with stored
            // hash

            assert hashedPassword != null;
            if (hashedPassword.equals(storedHash)) {
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("User logged in successfully.");
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("Valid user. Continuing...");
            } else {
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("Invalid user. Exiting...");
                System.out.println("\n----------------------------------------------------\n");
                System.exit(0);
            }
        }
        SecretKey secretKey = Cryptography.generateSecretKeyFromPassword(password);

        File keyFile = new File(keyFilePath);
        if (keyFile.exists()) {
            // Key file exists, decrypt the MEK from the file
            String encryptedMEK = Cryptography.readEncryptedMEK();
            mek = Cryptography.decryptMEK(encryptedMEK, secretKey);

        } else {
            // Key file doesn't exist, generate a new MEK
            mek = Cryptography.generateMEK();
            String encryptedMEK = Cryptography.encryptMEK(mek, secretKey);
            Cryptography.writeEncryptedMEK(encryptedMEK);

        }

        // Load file IDs from the fileIdMap
        existingEncryptedFileNames = new HashSet<>(fileIdMap.values());

        if (mek == null) {
            System.out.println("\n----------------------------------------------------\n");
            System.out.println("mek is not initialized. Please initialize it before calling searching().");
            return;
        }

        double startSearching;
        double endSearching;

        while (true) {
            System.out.println("\n----------------------------------------------------\n");
            System.out.print("Enter the keyword to search or press 'exit' to quit: ");
            String keyword = scanner.nextLine().trim().toLowerCase();
            System.out.println("\n----------------------------------------------------\n");
            if (keyword.equals("exit") || keyword.equals("stop") || keyword.equals("quit")) {
                break;
            }

            startSearching = System.currentTimeMillis() / 1000.0;
            String hashedKeyword = Cryptography.hashString(keyword, mek);
            if (index.containsKey(hashedKeyword)) {
                int keywordCount = index.get(hashedKeyword).values().stream()
                        .filter(Objects::nonNull)
                        .mapToInt(Integer::intValue)
                        .sum();
                System.out.println("Token ID is: " + keyword);
                System.out.println("\n----------------------------------------------------\n");
                System.out.println("Token Count is: " + keywordCount);
                System.out.println("\n----------------------------------------------------\n");
                for (Map.Entry<String, Integer> entry : index.get(hashedKeyword).entrySet()) {
                    Integer frequency = entry.getValue();
                    if (frequency != null) {
                        String docId = entry.getKey();
                        String fileName = fileIdMap.get(docId);
                        if (fileName != null) {
                            String decryptedFileName = Cryptography.decryptFileName(fileName, mek);
                            System.out
                                    .println(" Document is: " + decryptedFileName + ", Frequency is: " + frequency);
                        } else {
                            System.out.println(" Document is: null, Frequency is: " + frequency);
                        }
                    }
                    System.out.println();
                }

                System.out.println("\n----------------------------------------------------\n");
                endSearching = System.currentTimeMillis() / 1000.0;
                double totalSearchTime = endSearching - startSearching;
                System.out.println("The Time taken to search the keyword is: "
                        + String.format("%.4f", totalSearchTime) + " seconds");
                System.out.println("\n----------------------------------------------------\n");
            } else {
                System.out.println("The Token does not exist.");
                System.out.println();
                System.out.println("\n----------------------------------------------------\n");
            }
        }
    }

    private static void loadFileIdMapFromFile() {
        Type fileIdMapType = new TypeToken<Map<String, String>>() {
        }.getType();
        fileIdMap = JSONReader.readFromJsonFile(fileIdMapPath, fileIdMapType);
    }

    private static void loadIndexFromFile() {
        Type indexType = new TypeToken<Map<String, Map<String, Integer>>>() {
        }.getType();
        index = JSONReader.readFromJsonFile(indexPath, indexType);
    }

    /**
     * !Cryptography
     * 
     * @param hashString()
     * @param getPassword()
     * @param readEncryptedMEK()
     * @param writeEncryptedMEK()
     * @param encryptMEK()
     * @param decryptMEK()
     * @param hashPassword()
     * @param byteToHex()
     * @param readStoredHash()
     * @param storeHashedPassword()
     * @param generateFileId()
     * @param encryptFileName()
     * @param decryptFileName()
     * @throws IOException
     * @throws TikaException
     * @throws SAXException
     */
    public class Cryptography {
        /**
         * !Generating Secret Key From Password
         * 
         * @param password
         * @return
         */
        private static SecretKey generateSecretKeyFromPassword(String password) {
            try {
                int iterations = 10000;
                int keyLength = 256;
                char[] passwordChars = password.toCharArray();
                KeySpec spec = new PBEKeySpec(passwordChars, saltForEncryption, iterations, keyLength);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                // Existing code for generating the secret key
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        /**
         * !Generate Media Encryption Key(MEK)
         * 
         * @return
         * @throws NoSuchAlgorithmException
         */
        private static SecretKey generateMEK() throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        }

        /**
         * !Hash to the string(Tokens)
         * 
         * @param input
         * @param mek
         * @return
         */
        private static String hashString(String input, SecretKey mek) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(mek);
                byte[] hash = mac.doFinal(input.getBytes());
                StringBuilder hexString = new StringBuilder();
                for (byte b : hash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1)
                        hexString.append('0');
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
                return null;
            }
        }

        /**
         * !Registration
         * 
         * @param storedHash
         * @return
         */
        private static String getPassword(String storedHash) {

            Console console = System.console();
            char password[];
            if (console == null) {
                System.err.println("No console found. Please run this program from a command line.");
                System.exit(1);
            } else {
                if (storedHash == null) {
                    System.out.println("\n----------------------------------------------------\n");
                    password = console.readPassword("Create Password : ");
                    storedHash = new String(password);
                } else {
                    System.out.println("\n----------------------------------------------------\n");
                    password = console.readPassword("Enter Password : ");
                    storedHash = new String(password);
                }
            }
            return storedHash;
        }

        /**
         * !Read Encrypted Media Encryption Key(MEK)
         * 
         * @return
         * @throws IOException
         */
        private static String readEncryptedMEK() throws IOException {
            try (BufferedReader br = new BufferedReader(new FileReader(IndexingAndSearching.keyFilePath))) {
                return br.readLine().trim();
            }
        }

        /**
         * !Write Encrypted Media Encryption Key(MEK)
         * 
         * @return
         * @throws IOException
         */
        private static void writeEncryptedMEK(String encryptedMEK) throws IOException {
            try (FileWriter writer = new FileWriter(IndexingAndSearching.keyFilePath)) {
                writer.write(encryptedMEK);
            }
        }

        /**
         * !Encrypt Media Encryption Key(MEK)
         * 
         * @param mek
         * @param secretKey
         * @return
         */
        private static String encryptMEK(SecretKey mek, SecretKey secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedBytes = cipher.doFinal(mek.getEncoded());
                return Base64.getEncoder().encodeToString(encryptedBytes);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        private static SecretKey decryptMEK(String encryptedMEK, SecretKey secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMEK.replaceAll("\\s+", ""));

                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                return new SecretKeySpec(decryptedBytes, "AES");
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        private static String hashPassword(String password) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedHash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
                return bytesToHex(encodedHash);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }

        /**
         * !
         * 
         * @param hash
         * @return
         */
        private static String bytesToHex(byte[] hash) {
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        }

        /**
         * !Read Store Hash Password
         * 
         * @return
         */
        private static String readStoredHash() {
            File file = new File(PASSWORD_FILE);

            if (file.exists()) {
                try {
                    Path filePath = Paths.get(PASSWORD_FILE);
                    byte[] encoded = Files.readAllBytes(filePath);
                    return new String(encoded, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    e.printStackTrace();
                    return null;
                }
            } else {
                return null;
            }
        }

        /**
         * !Storing Hash Password
         * 
         * @param hashedPassword
         */
        private static void storeHashedPassword(String hashedPassword) {
            try {
                FileWriter writer = new FileWriter(PASSWORD_FILE);
                writer.write(hashedPassword);
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        /**
         * !Generate file ID
         * 
         * @param fileName
         * @return
         */
        public static String generateFileId(String fileName) {
            try {
                MessageDigest digest = MessageDigest.getInstance("MD5");
                byte[] hash = digest.digest(fileName.getBytes(StandardCharsets.UTF_8));
                BigInteger bigInt = new BigInteger(1, hash);
                return bigInt.toString(16);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return null;
        }

        /**
         * !Encrypt File Name
         * 
         * @param fileName
         * @param secretKey
         * @return
         */
        private static String encryptFileName(String fileName, SecretKey secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedBytes = cipher.doFinal(fileName.getBytes());
                return Base64.getEncoder().encodeToString(encryptedBytes);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        /**
         * !Decrypt File Name
         * 
         * @param encryptedFileName
         * @param secretKey
         * @return
         */
        private static String decryptFileName(String encryptedFileName, SecretKey secretKey) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedFileName));
                return new String(decryptedBytes);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }
    }
}
