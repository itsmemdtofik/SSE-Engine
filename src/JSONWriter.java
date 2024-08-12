import com.google.gson.Gson;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class JSONWriter {
    public static <T> void writeToJsonFile(T object, String filePath) {
        Gson gson = new Gson();
        String json = gson.toJson(object);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(json);
        } catch (IOException e) {
            e.printStackTrace();
            // Handle the exception as needed
        }
    }
}
