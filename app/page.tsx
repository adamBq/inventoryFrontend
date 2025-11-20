"use client";

import dynamic from "next/dynamic";

const CBOMVisualizer = dynamic(
  () => import("./components/CBOMVisualizer"),
  { ssr: false }
);

export default function Home() {
  return <CBOMVisualizer />;
}
