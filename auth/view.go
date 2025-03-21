package auth

import (
	"net/http"
)

type View struct {
	Route       string
	Middlewares []func(http.Handler) http.Handler
	Handler     http.Handler
}

// Middleware chaining
func chainMiddlewares(handler http.Handler, middlewares []func(http.Handler) http.Handler) http.Handler {
	if len(middlewares) != 0 {
		for i := 0; i < len(middlewares); i++ { // Apply middlewares in normal order
			handler = middlewares[i](handler)
		}
		return handler
	}
	return handler
}

// Routes function
func Routes(mux *http.ServeMux, views []View) {
	for _, view := range views {
		handlerWithMiddlewares := chainMiddlewares(view.Handler, view.Middlewares)
		mux.HandleFunc(view.Route, func(w http.ResponseWriter, r *http.Request) {
			handlerWithMiddlewares.ServeHTTP(w, r)
		})

	}
}
