<?php
// SA-LARAVEL-02: whereRaw/DB::raw with parameter bindings, no interpolation
$users = DB::table('users')
    ->whereRaw('name = ?', [$name])
    ->get();

$rows = DB::table('logs')
    ->select(DB::raw('count(*) as total'))
    ->get();
