<?php

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Factory\AppFactory;
use Slim\Psr7\Response;
use Slim\Exception\HttpNotFoundException;
use Spatie\SslCertificate\SslCertificate;
use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate\HostDoesNotExist;
use Iodev\Whois\Factory;

const DATE_FORMAT = 'd/m/Y';

require __DIR__ . '/../vendor/autoload.php';

$app = AppFactory::create();

function json_print(Response $response, array $data) {
    $payload = json_encode($data, JSON_PRETTY_PRINT);
    $response->getBody()->write($payload);
    return $response;
}

function cache_file($key, $value) {

    $cache_file = $key . '.txt';

    $cached_value = file_exists($cache_file) ? unserialize(file_get_contents($cache_file)) : null;

    if ($cached_value === null || time() - filemtime($cache_file) >= 300) {
        file_put_contents($cache_file, serialize($value));
        return $value;
    } else {
        return $cached_value;
    }
}

$app->add(new \Slim\HttpCache\Cache('public', 86400));

$cacheProvider = new \Slim\HttpCache\CacheProvider();

$app->add(function (Request $request, RequestHandler $handler) {
    $response = $handler->handle($request);
    return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus(200);
});

$app->get('/', function (Request $request, Response $response, $args) use ($cacheProvider): Response {
    $data = ['output' => 'Hello World..!'];
    $response = $cacheProvider->withEtag($response, 'abc');
    return json_print($response, $data);
});

$app->get('/ssl/{domain}', function (Request $request, Response $response, $args) use ($cacheProvider): Response {

    try {
        $domain = $args['domain'];
        $response = $cacheProvider->withEtag($response, 'abc');
        if (preg_match("/^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/", $domain)) {
            $certificate = SslCertificate::createForHostName($domain);
            $message = ['output' => $certificate->expirationDate()->isoFormat(DATE_FORMAT)];
            return json_print($response, $message);
        } else {
            return json_print($response, ['output' => 'domain is invalid']);
        }
    } catch (HostDoesNotExist $exc) {
        return json_print($response, ['output' => $exc->getMessage()]);
    } catch (ErrorException $exc) {
        return json_print($response, ['output' => $exc->getMessage()]);
    }
});

$app->get('/whois/{domain}', function (Request $request, Response $response, $args) use ($cacheProvider): Response {
    try {
        $domain = $args['domain'];
        $response = $cacheProvider->withEtag($response, 'abc');
         if (preg_match("/^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$/", $domain)) {
             
            $whois = Factory::get()->createWhois();
             
            $info = $whois->loadDomainInfo($domain);
            $cached = cache_file('whois_'.$domain, $info);
            
            if (!is_null($cached) && !empty($cached)) {
                $expirationDate = date(DATE_FORMAT, $cached->expirationDate);
                return json_print($response, ['output' => $expirationDate]);  
            } else {
                return json_print($response, ['output' => 'many requests']);
            }
         } else {
            return json_print($response, ['output' => 'domain is invalid']);
        } 
    } catch (\Exception $exc) {
        return json_print($response, ['output' => $exc->getMessage()]);
    }

});

$app->map(['GET'], '/{routes:.+}', function ($request, $response) {
    throw new HttpNotFoundException($request);
});

$app->run();
