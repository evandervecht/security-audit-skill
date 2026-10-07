<?php
// SA-LARAVEL-07: fixed internal endpoint, no user input in URL
class ProxyController
{
    public function fetch(Request $request): string
    {
        $allowed = 'https://api.internal.example.com/data';
        $response = Http::get($allowed);
        return $response->body();
    }
}
