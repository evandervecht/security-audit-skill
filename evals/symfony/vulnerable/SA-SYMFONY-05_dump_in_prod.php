<?php
namespace App\Controller;

class ProductController
{
    public function show(int $id)
    {
        $product = $this->repo->find($id);
        dump($product);
        return $this->render('product.html.twig', ['product' => $product]);
    }
}
