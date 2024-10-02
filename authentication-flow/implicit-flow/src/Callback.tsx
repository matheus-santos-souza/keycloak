import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom"
import { login } from "./utils";

export function Callback() {
  const { hash } = useLocation();
  //const { login, auth } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    /* if (auth) {
      navigate("/login");
      return;
    } */

    const searchParams = new URLSearchParams(hash.replace("#", ""));
    const accessToken = searchParams.get("access_token") as string;
    const idToken = searchParams.get("id_token") as string;
    const state = searchParams.get("state") as string;

    if (!accessToken || !idToken || !state) {
      navigate("/login");
    }

    login(accessToken, idToken, state);

  //}, [hash, login, auth, navigate]);
  }, [hash]);

  return <div>Loading...</div>;
}