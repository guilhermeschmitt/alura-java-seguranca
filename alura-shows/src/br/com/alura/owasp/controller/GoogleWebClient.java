package br.com.alura.owasp.controller;

import java.io.IOException;

import org.springframework.stereotype.Component;

import br.com.alura.owasp.retrofit.Resposta;
import br.com.alura.owasp.retrofit.RetrofitInicializador;
import retrofit2.Call;

@Component
public class GoogleWebClient {

	private static final String SECRET = "6LdTzz8UAAAAAEjZ0hEAgVQqhzUKzq4cCA1ETmT9";

	public boolean verifica(String recaptcha) throws IOException {
		Call<Resposta> token = new RetrofitInicializador().getGoogleService().enviaToken(SECRET, recaptcha);
		return token.execute().body().isSuccess();
	}
	
}
