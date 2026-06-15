<?php
// SA-LARAVEL-02: User input interpolated into raw SQL
$users = DB::table('users')
    ->whereRaw("name = $name")
    ->get();

$rows = DB::table('logs')
    ->select(DB::raw("count(*) as c WHERE owner = $id"))
    ->get();
