/*
 * MIT License
 * 
 * Copyright (c) 2024 Mohammad Tofik
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


import javax.swing.*;

import org.json.simple.parser.ParseException;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class OpenInterfaceDemo {

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

        try (Scanner scanner = new Scanner(System.in)) {
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
                    case 1:
                        openFileSelectionDialog();
                        break;
                    case 2:

                        break;
                    case 3:

                        break;
                    case 4:
                        System.out.println("Exiting...\n\n");
                        return;
                    default:
                        System.out.println("Invalid Choice!\n\n");
                }
            }
        }
    }

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

    public static void copyFile(Path source, Path destination) throws IOException {
        Files.copy(source, destination.resolve(source.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    }

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

