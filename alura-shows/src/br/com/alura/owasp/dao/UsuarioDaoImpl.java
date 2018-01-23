package br.com.alura.owasp.dao;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Repository;

import br.com.alura.owasp.model.Usuario;

@Repository
public class UsuarioDaoImpl implements UsuarioDao {

	@PersistenceContext
	EntityManager manager;
	
	public void salva(Usuario usuario) {
		encryptPasswordHash(usuario);
		manager.persist(usuario);
	}

	private void encryptPasswordHash(Usuario usuario) {
		String salt = BCrypt.gensalt();
		String senhaHash = BCrypt.hashpw(usuario.getSenha(), salt);
		usuario.setSenha(senhaHash);
	}

	public Usuario procuraUsuario(Usuario usuario) {
		TypedQuery<Usuario> query = manager.createQuery("SELECT u FROM Usuario u where u.email=:email", Usuario.class);
		query.setParameter("email", usuario.getEmail());
		Usuario user = query.getResultList().stream().findFirst().orElse(null);
		
		if(descryptPasswordHash(usuario, user)) {
			return user;			
		}
		
		return null;
	}

	private boolean descryptPasswordHash(Usuario usuario, Usuario user) {
		if(user==null) {
			return false;
		}
		return BCrypt.checkpw(usuario.getSenha(), user.getSenha());
	}
}
