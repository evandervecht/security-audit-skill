<?php
// SA-LARAVEL-07: SSRF via user-supplied URL
class ProxyController
{
    public function fetch(Request $request): string
    {
        $response = Http::get($request->input('url'));
        return $response->body();
    }
}
