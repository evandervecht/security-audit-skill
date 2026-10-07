<?php
// SA-LARAVEL-04: read configuration via config() helper
class StripeService
{
    public function charge(): string
    {
        $key = config('services.stripe.secret');
        return $key;
    }
}
