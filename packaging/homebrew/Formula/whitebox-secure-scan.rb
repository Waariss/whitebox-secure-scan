class WhiteboxSecureScan < Formula
  include Language::Python::Virtualenv

  desc "Offline white-box secure-code triage for penetration testers"
  homepage "https://github.com/Waariss/whitebox-secure-scan"
  url "https://files.pythonhosted.org/packages/f5/64/086d75485d2bbd93b7463bf44045b356013f5d1d2d019e335e9be23cb59f/whitebox_secure_scan-1.1.0.tar.gz"
  sha256 "5db324920268b229ea9ec1e602a6436feb006442bf5384263373f33b5d79ea46"
  license "Apache-2.0"

  depends_on "python@3.14"

  resource "attrs" do
    url "https://files.pythonhosted.org/packages/9a/8e/82a0fe20a541c03148528be8cac2408564a6c9a0cc7e9171802bc1d26985/attrs-26.1.0.tar.gz"
    sha256 "d03ceb89cb322a8fd706d4fb91940737b6642aa36998fe130a9bc96c985eff32"
  end

  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/36/3d/ca032d5ac064dff543aa13c984737795ac81abc9fb130cd2fcff17cfabc7/jsonschema-4.17.3.tar.gz"
    sha256 "0f864437ab8b6076ba6707453ef8f98a6a0d512a80e93f8abdb676f737ecb60d"
  end

  resource "PyYAML" do
    url "https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz"
    sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
  end

  resource "pyrsistent" do
    url "https://files.pythonhosted.org/packages/ce/3a/5031723c09068e9c8c2f0bc25c3a9245f2b1d1aea8396c787a408f2b95ca/pyrsistent-0.20.0.tar.gz"
    sha256 "4c48f78f62ab596c679086084d0dd13254ae4f3d6c72a83ffdf5ebdef8f265a4"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s,
                 shell_output("#{bin}/whitebox-secure-scan version")
    assert_match "Offline white-box secure-code triage",
                 shell_output("#{bin}/whitebox-secure-scan --help 2>&1")

    repository = testpath / "synthetic-repository"
    repository.mkpath
    (repository / "sample.py").write <<~PYTHON
      def hello():
          return "hello"
    PYTHON
    results = testpath / "review-results"

    system bin / "whitebox-secure-scan", "review", repository, "--output", results
    assert_path_exists results / "SUMMARY.md"
    assert_path_exists results / "report.md"
    assert_path_exists results / "findings.json"
  end
end
