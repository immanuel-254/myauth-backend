package auth

import (
	"context"

	"github.com/a-h/templ"
)

func base(title, link string, template func(route string) templ.Component) string {
	component := EmailBaseTemplate(title, template(link))
	htmlString, err := templ.ToGoHTML(context.Background(), component)
	if err != nil {
		panic(err)
	}

	// htmlString now holds your component as a string
	stringValue := string(htmlString)

	return stringValue
}

func EmailVerificationTemplate(route string) string {
	return base("Verify Email", route, EmailVerification)
}

func ChangeEmailVerificationTemplate(route string) string {
	return base("Change Email", route, ChangeEmailVerification)
}

func ChangePasswordVerificationTemplate(route string) string {
	return base("Change Password", route, ChangePasswordVerifcation)
}

func ResetPasswordVerificationTemplate(route string) string {
	return base("Reset Password", route, ResetPasswordVerification)
}

func DeleteUserVerificationTemplate(route string) string {
	return base("Delete User", route, DeleteUserVerification)
}
