<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Slim\Exception\HttpNotFoundException;
use Spatie\SslCertificate\SslCertificate;
use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate\HostDoesNotExist;
use Iodev\Whois\Factory;

const DATE_FORMAT = 'd/m/Y';

require __DIR__ . '/../vendor/autoload.php';

function cache ($key, $data) {
    $cache_file = $key . '.txt';
    $cached_value = file_exists($cache_file) ? file_get_contents($cache_file) : null;
    if ($cached_value === null || time() - filemtime($cache_file) >= 60) {
        file_put_contents($cache_file, $data);
        return $data;
    } else {
        return $cached_value;
    }
}

$app = AppFactory::create();

$app->addRoutingMiddleware();

$errorMiddleware = $app->addErrorMiddleware(true, true, true);

$app->get('/', function (Request $request, Response $response, $args) {
    $output = ['output' => 'Hello World..!'];

    return new JsonResponse($output, 200, [], JSON_PRETTY_PRINT);
});

$app->get('/whois/{domain}', function (Request $request, Response $response, $args) {
    try {
        $domain = $args['domain'];
         if (preg_match("/^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/", $domain)) {
             
            $whois = Factory::get()->createWhois();
             
            $info = $whois->loadDomainInfo($domain);
            
            $data = unserialize(cache('whois_'.$domain, serialize($info)));
             
             if (!is_null($data) && !empty($data)) {
                $expirationDate = date(DATE_FORMAT, $data->expirationDate);
                return new JsonResponse(['output' => $expirationDate], 200, [], JSON_PRETTY_PRINT);                 
             } else {
                return new JsonResponse(['output' => 'many requests'], 200, [], JSON_PRETTY_PRINT);  
             }
         } else {
            return new JsonResponse(['output' => 'domain is invalid'], 200, [], JSON_PRETTY_PRINT);
        } 
    } catch (Exception $exc) {
        return new JsonResponse(['output' => $exc->getMessage()], 200, [], JSON_PRETTY_PRINT);
    }

});

$app->get('/ssl/{domain}', function(Request $request, Response $response, $args) {
    
    try {
        $domain = $args['domain'];
        if (preg_match("/^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/", $domain)) {
            $certificate = SslCertificate::createForHostName($domain);
            $data = unserialize(cache('ssl_'.$domain, serialize($certificate)));
            $message = ['output' => $data->expirationDate()->isoFormat(DATE_FORMAT)];
            return new JsonResponse($message, 200, [], JSON_PRETTY_PRINT);
        } else {
            return new JsonResponse(['output' => 'domain is invalid'], 200, [], JSON_PRETTY_PRINT);
        }        
    } catch (HostDoesNotExist $exc) {
        return new JsonResponse(['output' => $exc->getMessage()], 200, [], JSON_PRETTY_PRINT);
    } catch (ErrorException $exc) {
        return new JsonResponse(['output' => $exc->getMessage()], 200, [], JSON_PRETTY_PRINT);
    }
    
});

$app->map(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], '/{routes:.+}', function ($request, $response) {
    throw new HttpNotFoundException($request);
});

$app->run();