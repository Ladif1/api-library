import { User } from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { Buffer } from "buffer"; // Pour décoder Base64
import { notFound } from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key"; // Clé secrète pour signer le token

// Droits en fonction du rôle
export type Role = 'admin' | 'gerant' | 'utilisateur';

export const permissionsByRole: Record<Role, { canRead: string[], canWrite: string[], canDelete: string[] }> = {
  admin: {
    canRead: ['authors', 'books', 'book-collections', 'users'],
    canWrite: ['authors', 'books', 'book-collections', 'users'],
    canDelete: ['authors', 'books', 'book-collections', 'users'],
  },
  gerant: {
    canRead: ['authors', 'books', 'book-collections', 'users'],
    canWrite: ['authors', 'books', 'book-collections', 'users'],
    canDelete: ['book-collections'], // Seulement supprimer dans "bookCollection"
  },
  utilisateur: {
    canRead: ['authors', 'books', 'book-collections', 'users'],
    canWrite: ['books'], // Peut créer un livre si l'auteur existe
    canDelete: [], // Aucun droit de suppression
  },
};

export class AuthenticationService {
  private getRole(username: string): string {
    // Assigner des rôles selon l'username
    switch (username) {
      case 'admin':
        return 'admin';
      case 'gerant':
        return 'gerant';
      case 'utilisateur':
        return 'utilisateur';
      default:
        throw new Error('Invalid username');
    }
  }

  public async authenticate(
    username: string,
    password: string
  ): Promise<string> {
    // Recherche l'utilisateur dans la base de données
    const user = await User.findOne({ where: { username } });

    if (!user) {
      throw notFound("User");
    }

    // Décoder le mot de passe stocké en base de données
    const decodedPassword = atob(user.password);

    // Vérifie si le mot de passe est correct
    if (password === decodedPassword) {
      const role = this.getRole(username);
      const permissions = permissionsByRole[role as Role];

      // Si l'utilisateur est authentifié, on génère un JWT
      const token = jwt.sign({ username: user.username, role, permissions }, JWT_SECRET, {
        expiresIn: "1h",
      });
      return token;
    } else {
      let error = new Error("Wrong password");
      (error as any).status = 403;
      throw error;
    }
  }
}

export const authService = new AuthenticationService();
