<?php
namespace App\Controller;

use Symfony\Component\Yaml\Yaml;
use Symfony\Component\HttpFoundation\Request;

class ImportController
{
    public function import(Request $request)
    {
        $data = Yaml::parse($request->getContent());
        return $this->process($data);
    }
}
