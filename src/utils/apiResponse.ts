// Interface TypeScript définissant le contrat d'une réponse API uniforme (RGPD & robustesse)
export interface ApiResponse<T = unknown> {
  // Indicateur booléen de succès ou d'échec de la requête
  success: boolean;
  // Message informatif destiné au client ou aux logs
  message?: string;
  // Données renvoyées (optionnelles en cas d'erreur ou d'absence de contenu)
  data?: T;
  // Horodatage ISO 8601 pour l'audit et la traçabilité des échanges
  timestamp: string;
}

// Fonction utilitaire pour construire une réponse standardisée
export const sendResponse = <T>(
  success: boolean,
  message?: string,
  data?: T
): ApiResponse<T> => {
  return {
    // Statut de l'opération
    success,
    // Message descriptif
    message,
    // Données de charge utile
    data,
    // Génération de la date courante au format ISO UTC
    timestamp: new Date().toISOString()
  };
};

