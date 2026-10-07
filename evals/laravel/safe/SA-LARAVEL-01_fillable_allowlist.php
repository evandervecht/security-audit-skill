<?php
// SA-LARAVEL-01: Explicit fillable allowlist, sensitive fields guarded
class Post extends Model
{
    protected $guarded = ['id', 'is_admin'];
    protected $fillable = ['title', 'body', 'category_id'];
}
