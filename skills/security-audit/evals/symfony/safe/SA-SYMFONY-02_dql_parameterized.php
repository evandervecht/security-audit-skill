<?php
namespace App\Repository;

class UserRepository
{
    public function search(string $name)
    {
        return $this->em->createQuery(
            'SELECT u FROM App\Entity\User u WHERE u.name = :name'
        )->setParameter('name', $name)->getResult();
    }
}
