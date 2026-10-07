<?php
// SA-LARAVEL-04: env() called in app code instead of config()
class StripeService
{
    public function charge(): string
    {
        $key = env('STRIPE_SECRET');
        return $key;
    }
}
