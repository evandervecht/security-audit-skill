<?php
namespace App\Controller;

use Symfony\Component\Yaml\Yaml;

class ImportController
{
    public function loadConfig()
    {
        // Parses a trusted, bundled config file shipped with the app
        $data = Yaml::parseFile(__DIR__ . '/../../config/import_defaults.yaml');
        return $this->process($data);
    }
}
