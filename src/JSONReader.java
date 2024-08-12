import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Map;

@SuppressWarnings("unused")
public class JSONReader {
    public static <T> T readFromJsonFile(String filePath, Type type) {
        Gson gson = new Gson();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String json = reader.readLine();
            return gson.fromJson(json, type);
        } catch (IOException e) {
            e.printStackTrace();
            // Handle the exception as needed
        }

        return null;
    }
}
