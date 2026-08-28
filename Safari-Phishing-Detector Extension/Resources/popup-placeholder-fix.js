(() => {
  const originalGetMessage = getMessage;
  window.getMessage = (key, substitutions) => {
    let message = originalGetMessage(key, substitutions);
    const values = substitutions ? (Array.isArray(substitutions) ? substitutions : [substitutions]) : [];
    values.forEach((value, index) => {
      message = message.split(`$${index + 1}`).join(String(value));
    });
    return message;
  };
})();
