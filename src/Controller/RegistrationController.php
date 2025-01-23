<?php

namespace App\Controller;

use App\Entity\Users;
use App\Form\RegistrationFormType;
use App\Repository\UsersRepository;
use App\Services\JWTService;
use App\Services\SendEmailService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class RegistrationController extends AbstractController
{
    #[Route('/inscription', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $userPasswordHasher,
        Security $security,
        EntityManagerInterface $entityManager,
        JWTService $jwt,
        SendEmailService $mail
    ): Response
    {
        $user = new Users();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            // encode the plain password
            $user->setPassword($userPasswordHasher->hashPassword($user, $plainPassword));

            $entityManager->persist($user);
            $entityManager->flush();
            //Generer le token + envoi email
            //Creer entete (header) + payload (les données)
            //Type + hash
            $header = [
                'type' => 'JWT',
                'alg' => 'HS256'
            ];
            //Le payload
            $payload = [
                //Get USer ID apres persist
                'user_id' => $user->getId(),

            ];
            //Generer le token a l'aide de generate de JWTService
            $token = $jwt->generate($header, $payload, $this->getParameter('app.jwtsecret'));

            //Mettre le token dans url de l'email
            $mail->SendEmail(
                'no-replay@blog.com',
                $user->getEmail(),
                'Activation de votre compte mic-blog',
                'register',
                compact('user', 'token') // ["user" => $user, "token" => $token] = equivalent sans compact
            );

            // do anything else you need here, like send an email
            $this->addFlash('warning', 'Merci de valider votre inscription avec le lien envoyé sur votre boite mail !');
            return $this->redirectToRoute('app_login');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }

    #[Route('/validation/{token}', name: 'app_verify_user')]
    public function VerityUser($token, JWTService $jwt, UsersRepository $usersRepository, EntityManagerInterface $em): Response{
        //Le token est il valide => juste ,on expiré, + signature
        if($jwt->isValid($token) && !$jwt->isExpired($token) && $jwt->check($token, $this->getParameter("app.jwtsecret"))){
            //On recupere les données => le payload
            $payload = $jwt->getPayload($token);

            //Check si payload et user match
            $user = $usersRepository->find($payload['user_id']);
            //Check si user et pas actif
            if($user && !$user->isVerified()){
                //Change la valeur du bool et enregistre
                $user->setVerified(true);
                $em->flush();

                $this->addFlash('success', 'Merci d\'avoir activé votre compte Mic-Blog !');
                return $this->redirectToRoute('app_login');
            }
        }
        $this->addFlash('danger', 'Erreur lors de l\'activation de votre compte Mic-Blog !');
        return $this->redirectToRoute('app_register');
    }
}
