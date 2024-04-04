package Utils


type Tools struct {
	Mobsf bool `form:"Mobsf"`
	Vt bool `form:"Vt"`
	Apkid bool `form:"Apkid"`
	Exodus bool `form:"Exodus"`
	Ssdeep bool `form:"Ssdeep"`
	Quark bool `form:"Quark"`
	Androguard bool `form:"Androguard"`
}

func AllToolsFalse(tools Tools) bool {
    return !tools.Mobsf && !tools.Vt && !tools.Apkid && !tools.Exodus && !tools.Ssdeep && !tools.Quark && !tools.Androguard
}