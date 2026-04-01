// SA-CS-01: Safe deserialization using System.Text.Json
using System.Text.Json;

public class DataImporter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public UserDto ImportData(Stream requestBody)
    {
        return JsonSerializer.Deserialize<UserDto>(requestBody, Options);
    }
}
