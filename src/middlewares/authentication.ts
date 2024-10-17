import * as express from "express";
import * as jwt from "jsonwebtoken";
import { permissionsByRole, Role } from "../services/authentication.service";

export function expressAuthentication(
  request: express.Request,
  securityName: string,
  requiredPermissions?: { canRead?: string[], canWrite?: string[], canDelete?: string[] }
): Promise<any> {
  if (securityName === "jwt") {
    const token =
      request.body.token ||
      request.query.token ||
      request.headers["authorization"]?.split(' ')[1];

    return new Promise((resolve, reject) => {
      if (!token) {
        reject(new Error("No token provided"));
      }
      jwt.verify(
        token,
        process.env.JWT_SECRET ?? "your_jwt_secret_key",
        function (err: any, decoded: any) {
          if (err) {
            reject(err);
          } const userRole: Role = decoded.role; // Assurez-vous que le rôle est inclus dans le token

          // Vérification des permissions basées sur le rôle
          const permissions = permissionsByRole[userRole];

          const path = request.path.split("/")[1];
          console.log("path", path);
          console.log(permissions.canDelete);
          switch (request.method) {
            case "GET":
              if (!permissions.canRead.includes(path)) {
                reject(new Error("Unauthorized"));
              }
              break;
            case "POST":
              if (!permissions.canWrite.includes(path)) {
                reject(new Error("Unauthorized"));
              }
              break;
            case "DELETE":
              if (!permissions.canDelete.includes(path)) {
                console.log("mais nan");
                reject(new Error("Unauthorized"));
              }
              break;
            default:
              reject(new Error("Method not allowed"));
          }

          resolve(decoded);

        }
      );
    });
  } else {
    throw new Error("Only support JWT securityName");
  }
}
