import bcrypt from 'bcrypt';

export const passwordService = {
  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  },

  async comparePassword(plainPassword: string, hashedPassword: string) {
    return bcrypt.compare(plainPassword, hashedPassword);
  },
};
