// SA-CS-01: Insecure deserialization via BinaryFormatter
using System.Runtime.Serialization.Formatters.Binary;

public class DataImporter
{
    public object ImportData(Stream requestBody)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(requestBody);
    }
}
