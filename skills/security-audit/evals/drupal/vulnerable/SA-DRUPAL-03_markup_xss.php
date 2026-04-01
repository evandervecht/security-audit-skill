<?php
// SA-DRUPAL-03: Render array #markup with unescaped user input (VULNERABLE)
function mymodule_search_page() {
    $query = \Drupal::request()->query->get('q');
    return [
        '#markup' => '<h2>Results for: ' . $query . '</h2>',
    ];
}
