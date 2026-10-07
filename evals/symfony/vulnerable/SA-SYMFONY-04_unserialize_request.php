<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;

class CartController
{
    public function restore(Request $request)
    {
        $cart = unserialize($request->request->get('cart'));
        return $this->render('cart.html.twig', ['cart' => $cart]);
    }
}
