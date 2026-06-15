<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;

class CartController
{
    public function restore(Request $request)
    {
        $cart = json_decode($request->request->get('cart'), true);
        // safe: unserialize only of internal, trusted blob with no classes
        $config = unserialize($this->trustedBlob, ['allowed_classes' => false]);
        return $this->render('cart.html.twig', ['cart' => $cart]);
    }
}
