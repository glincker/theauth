---
"@glinr/theauth-ui": minor
"@glinr/theauth-dashboard": patch
---

Accessibility pass on the default components. Errors are announced (`role="alert"`), field errors are linked to their input with `aria-describedby` and `aria-invalid`, the loading button sets `aria-busy`, the verification code digits and backup code input have accessible names inside a labelled group, and the auth card is a region named by its title. The default slots now live in one shared module instead of four copies.
