<?php

namespace App\Controller;

use App\Form\ResetPasswordFormType;
use App\Form\ResetPasswordType;
use App\Repository\UsersRepository;
use App\Services\JWTService;
use App\Services\SendEmailService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route(path: '/connexion', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/deconnexion', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    #[Route(path: '/mot-de-passe-oublier', name: 'app_forgotten_password')]
    public function forgottenPassWord(
        Request $request,
        UsersRepository $usersRepository,
        JWTService $jwt,
        UrlGeneratorInterface $url,
        SendEmailService $mail

    ):Response
    {
        //Formulaire
        $form = $this->createForm(ResetPasswordType::class);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $user = $usersRepository->findOneByEmail($form->get('email')->getData());
            //dd($user);
            if($user){
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

                //Url vers le nouveau mot de passe
                $url->generate("app_new_password", ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

                $mail->SendEmail(
                    'no-reply@blog.com',
                    $user->getEmail(),
                    'Modifier le mot de passe de votre compte mic-blog',
                    'new_password',
                    compact('user', 'url') // ["user" => $user, "url" => $url] = equivalent sans compact
                );

                $this->addFlash("success", "Email envoyé avec succès !");
                return $this->redirectToRoute("app_login");
        }
        $this->addFlash("danger", "Erreur lor de la réinitialisation du mot de passe !");
        return $this->redirectToRoute("app_login");
    }

        return $this->render("security/reset_password.html.twig",[
            "reset_password_form" => $form->createView()
        ]);
    }

    #[Route(path: '/nouveau-mot-de-passe/{token}', name: 'app_new_password')]
    public function newPassword(
        $token,
        JWTService $jwt,
        UsersRepository $usersRepository,
        EntityManagerInterface $em,
        Request $request,
        UserPasswordHasherInterface $hasher
    ):Response{
        //Le token est il valide => juste ,on expiré, + signature
        if($jwt->isValid($token) && !$jwt->isExpired($token) && $jwt->check($token, $this->getParameter("app.jwtsecret"))){
            //On recupere les données => le payload
            $payload = $jwt->getPayload($token);

            //Check si payload et user match
            $user = $usersRepository->find($payload['user_id']);
            //Check si user et pas actif
            if($user){
                $form = $this->createForm(ResetPasswordFormType::class);
                $form->handleRequest($request);
                if($form->isSubmitted() && $form->isValid()){
                    $user->setPassword(
                        $hasher->hashPassword($user, $form->get("password")->getData())
                    );
                    $em->flush();

                    $this->addFlash('success', 'Votre mot de passe a bien été modifié votre compte Mic-Blog !');
                    return $this->redirectToRoute('app_login');
                }

            }
        }
        $this->addFlash('danger', 'Erreur lors de la création du nouveau mot de passe pour votre compte Mic-Blog !');
        return $this->redirectToRoute('app_register');
    }
}
