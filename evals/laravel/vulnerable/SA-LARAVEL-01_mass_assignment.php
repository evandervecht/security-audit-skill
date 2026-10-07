<?php
// SA-LARAVEL-01: Mass assignment protection disabled
class Post extends Model
{
    protected $guarded = [];
}

class User extends Model
{
    public static function boot()
    {
        parent::boot();
        User::unguard();
    }
}
