<?php
namespace App\Services;

use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;

class SendEmailService{
    //MailerInterface
    private MailerInterface $mailer;
    public function __construct(MailerInterface $mailer){
        $this->mailer = $mailer;
    }

    public function SendEmail(
        string $from,
        string $to,
        string $subject,
        string $template,
        array $context
    ): void{
        //Creer email
        $email = (new TemplatedEmail())
            ->from($from)
            ->to($to)
            ->subject($subject)
            ->htmlTemplate("emails/$template.html.twig")
            ->context($context);
        //Envoyer l'email
        $this->mailer->send($email);
    }
}
