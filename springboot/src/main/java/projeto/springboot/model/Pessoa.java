package projeto.springboot.model;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
public class Pessoa implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	@NotBlank(message = "Nome precisa ser preenchido")
	private String nome;

	@NotBlank(message = "Sobrenome precisa ser preenchido")
	private String sobrenome;

	@Min(value = 18, message = "Idade inválida")
	private int idade;

	@OneToMany(mappedBy = "pessoa", orphanRemoval = true, cascade = CascadeType.ALL)
	private List<Telefone> telefones;

	private String cep;
	private String rua;
	private String bairro;
	private String cidade;
	private String uf;
	private String ibge;

	private String sexopessoa;

	@ManyToOne
	private Profissao profissao;

	@Enumerated(EnumType.STRING)
	private Cargo cargo;

	public Cargo getCargo() {
		return cargo;
	}

	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@Temporal(TemporalType.DATE)
	private Date dataNascimento;

	@Lob
	private byte[] curriculo;

	private String nomeFileCurriculo;
	private String tipoFileCurriculo;

	public String getNomeFileCurriculo() {
		return nomeFileCurriculo;
	}

	public void setNomeFileCurriculo(String nomeFileCurriculo) {
		this.nomeFileCurriculo = nomeFileCurriculo;
	}

	public String getTipoFileCurriculo() {
		return tipoFileCurriculo;
	}

	public void setTipoFileCurriculo(String tipoFileCurriculo) {
		this.tipoFileCurriculo = tipoFileCurriculo;
	}

	public byte[] getCurriculo() {
		return curriculo;
	}

	public void setCurriculo(byte[] curriculo) {
		this.curriculo = curriculo;
	}

	public Date getDataNascimento() {
		return dataNascimento;
	}

	public void setDataNascimento(Date dataNascimento) {
		this.dataNascimento = dataNascimento;
	}

	public void setCargo(Cargo cargo) {
		this.cargo = cargo;
	}

	public Pessoa() {
		// TODO Auto-generated constructor stub
	}

	public String getSexopessoa() {
		return sexopessoa;
	}

	public void setSexopessoa(String sexopessoa) {
		this.sexopessoa = sexopessoa;
	}

	public Profissao getProfissao() {
		return profissao;
	}

	public void setProfissao(Profissao profissao) {
		this.profissao = profissao;
	}

	public String getCep() {
		return cep;
	}

	public void setCep(String cep) {
		this.cep = cep;
	}

	public String getRua() {
		return rua;
	}

	public void setRua(String rua) {
		this.rua = rua;
	}

	public String getBairro() {
		return bairro;
	}

	public void setBairro(String bairro) {
		this.bairro = bairro;
	}

	public String getCidade() {
		return cidade;
	}

	public void setCidade(String cidade) {
		this.cidade = cidade;
	}

	public String getUf() {
		return uf;
	}

	public void setUf(String uf) {
		this.uf = uf;
	}

	public String getIbge() {
		return ibge;
	}

	public void setIbge(String ibge) {
		this.ibge = ibge;
	}

	public List<Telefone> getTelefones() {
		return telefones;
	}

	public void setTelefones(List<Telefone> telefones) {
		this.telefones = telefones;
	}

	public int getIdade() {
		return idade;
	}

	public void setIdade(int idade) {
		this.idade = idade;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getSobrenome() {
		return sobrenome;
	}

	public void setSobrenome(String sobrenome) {
		this.sobrenome = sobrenome;
	}

}
