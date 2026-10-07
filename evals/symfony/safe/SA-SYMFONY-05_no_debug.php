<?php
namespace App\Controller;

class ProductController
{
    public function show(int $id)
    {
        $product = $this->repo->find($id);
        // Note: never leave debug dumps in production code.
        $this->logger->info('loaded product');
        return $this->render('product.html.twig', ['product' => $product]);
    }
}
